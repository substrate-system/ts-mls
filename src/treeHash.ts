import { encodeUint32, decodeUint32 } from './codec/number.js'
import { encodeOptional, decodeOptional } from './codec/optional.js'
import type { Decoder } from './codec/tlsDecoder.js'
import { mapDecoders, flatMapDecoder } from './codec/tlsDecoder.js'
import type { Encoder } from './codec/tlsEncoder.js'
import { contramapEncoders } from './codec/tlsEncoder.js'
import { encodeVarLenData, decodeVarLenData } from './codec/variableLength.js'
import type { Hash } from './crypto/hash.js'
import type { LeafNode } from './leafNode.js'
import { encodeLeafNode, decodeLeafNode } from './leafNode.js'
import { InternalError } from './mlsError.js'
import { encodeNodeType, decodeNodeType } from './nodeType.js'
import type { ParentNode } from './parentNode.js'
import { encodeParentNode, decodeParentNode } from './parentNode.js'
import type { RatchetTree } from './ratchetTree.js'
import type { NodeIndex } from './treemath.js'
import { rootFromNodeWidth, isLeaf, nodeToLeafIndex, left, right } from './treemath.js'

export type TreeHashInput = LeafNodeHashInput | ParentNodeHashInput
type LeafNodeHashInput = {
  nodeType: 'leaf'
  leafIndex: number
  leafNode: LeafNode | undefined
}
type ParentNodeHashInput = {
  nodeType: 'parent'
  parentNode: ParentNode | undefined
  leftHash: Uint8Array
  rightHash: Uint8Array
}

export const encodeLeafNodeHashInput: Encoder<LeafNodeHashInput> = contramapEncoders(
    [encodeNodeType, encodeUint32, encodeOptional(encodeLeafNode)],
    (input) => [input.nodeType, input.leafIndex, input.leafNode] as const,
)

export const decodeLeafNodeHashInput: Decoder<LeafNodeHashInput> = mapDecoders(
    [decodeUint32, decodeOptional(decodeLeafNode)],
    (leafIndex, leafNode) => ({
        nodeType: 'leaf',
        leafIndex,
        leafNode,
    }),
)

export const encodeParentNodeHashInput: Encoder<ParentNodeHashInput> = contramapEncoders(
    [encodeNodeType, encodeOptional(encodeParentNode), encodeVarLenData, encodeVarLenData],
    (input) => [input.nodeType, input.parentNode, input.leftHash, input.rightHash] as const,
)

export const decodeParentNodeHashInput: Decoder<ParentNodeHashInput> = mapDecoders(
    [decodeOptional(decodeParentNode), decodeVarLenData, decodeVarLenData],
    (parentNode, leftHash, rightHash) => ({
        nodeType: 'parent',
        parentNode,
        leftHash,
        rightHash,
    }),
)

export const encodeTreeHashInput: Encoder<TreeHashInput> = (input) => {
    switch (input.nodeType) {
        case 'leaf':
            return encodeLeafNodeHashInput(input)
        case 'parent':
            return encodeParentNodeHashInput(input)
    }
}
export const decodeTreeHashInput: Decoder<TreeHashInput> = flatMapDecoder(
    decodeNodeType,
    (nodeType): Decoder<TreeHashInput> => {
        switch (nodeType) {
            case 'leaf':
                return decodeLeafNodeHashInput
            case 'parent':
                return decodeParentNodeHashInput
        }
    },
)

export async function treeHashRoot (tree: RatchetTree, h: Hash): Promise<Uint8Array> {
    return treeHash(tree, rootFromNodeWidth(tree.length), h)
}

export async function treeHash (tree: RatchetTree, subtreeIndex: NodeIndex, h: Hash): Promise<Uint8Array> {
    if (isLeaf(subtreeIndex)) {
        const leafNode = tree[subtreeIndex]
        if (leafNode?.nodeType === 'parent') throw new InternalError('Somehow found parent node in leaf position')
        const input = encodeLeafNodeHashInput({
            nodeType: 'leaf',
            leafIndex: nodeToLeafIndex(subtreeIndex),
            leafNode: leafNode?.leaf,
        })
        return await h.digest(input)
    } else {
        const parentNode = tree[subtreeIndex]
        if (parentNode?.nodeType === 'leaf') throw new InternalError('Somehow found leaf node in parent position')
        const leftHash = await treeHash(tree, left(subtreeIndex), h)
        const rightHash = await treeHash(tree, right(subtreeIndex), h)
        const input = {
            nodeType: 'parent',
            parentNode: parentNode?.parent,
            leftHash,
            rightHash,
        } as const

        return await h.digest(encodeParentNodeHashInput(input))
    }
}
